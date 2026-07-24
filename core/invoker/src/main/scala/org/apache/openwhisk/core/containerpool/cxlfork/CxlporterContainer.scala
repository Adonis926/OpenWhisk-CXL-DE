/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0.
 */

package org.apache.openwhisk.core.containerpool.cxlfork

import java.io.{BufferedReader, InputStreamReader, OutputStreamWriter}
import java.net.{InetSocketAddress, Socket}
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

import akka.actor.ActorSystem
import akka.stream.scaladsl.Source
import akka.util.ByteString
import org.apache.openwhisk.common.{Logging, TransactionId}
import org.apache.openwhisk.core.containerpool.{Container, ContainerAddress, ContainerId, Interval}
import org.apache.openwhisk.core.entity._
import spray.json._

import scala.concurrent.duration._
import scala.concurrent.{blocking, ExecutionContext, Future}
import scala.util.Try

case class CxlporterContainerConfig(enabled: Boolean,
                                    host: String,
                                    port: Int,
                                    connectTimeout: FiniteDuration,
                                    requestTimeout: FiniteDuration)

/**
 * An OpenWhisk Container implementation backed by the paper CXLP/2 endpoint.
 *
 * It deliberately represents one logical, persistent ghost rather than a
 * Docker runtime container created by OpenWhisk. The target-side Docker ghost
 * owns /dev/cxlfork and forks a capsule runtime for each ACTIVATE request.
 */
class CxlporterContainer(override protected val id: ContainerId,
                         endpointHost: String,
                         endpointPort: Int,
                         connectTimeout: FiniteDuration,
                         requestTimeout: FiniteDuration,
                         owner: String,
                         function: String,
                         capsuleVersion: String)(implicit override protected val as: ActorSystem,
                                                 override protected val logging: Logging,
                                                 override protected val ec: ExecutionContext)
    extends Container {

  override protected[core] val addr = ContainerAddress("cxlfork-ghost.invalid", 1)

  private val tokenPattern = "^[A-Za-z0-9_.:-]+$".r

  private def requireToken(name: String, value: String): String = {
    require(tokenPattern.pattern.matcher(value).matches(), s"invalid $name token")
    value
  }

  require(endpointPort > 0 && endpointPort <= 65535, "invalid CXLP/2 port")
  requireToken("owner", owner)
  requireToken("function", function)
  requireToken("version", capsuleVersion)

  override def initialize(initializer: JsObject,
                          timeout: FiniteDuration,
                          maxConcurrent: Int,
                          entity: Option[WhiskAction] = None)(implicit transid: TransactionId): Future[Interval] = {
    val now = Instant.now()
    Future.successful(Interval(now, now))
  }

  override def suspend()(implicit transid: TransactionId): Future[Unit] =
    Future.successful(())

  override def resume()(implicit transid: TransactionId): Future[Unit] =
    Future.successful(())

  override def destroy()(implicit transid: TransactionId): Future[Unit] =
    Future.successful(())

  override def logs(limit: ByteSize, waitForSentinel: Boolean)(
    implicit transid: TransactionId): Source[ByteString, Any] =
    Source.empty

  override def run(
    parameters: JsValue,
    environment: JsObject,
    timeout: FiniteDuration,
    maxConcurrent: Int,
    maxResponse: ByteSize,
    truncation: ByteSize,
    reschedule: Boolean = false)(implicit transid: TransactionId): Future[(Interval, ActivationResponse)] = Future {
    blocking {
      val wallStart = Instant.now()
      val monotonicStart = System.nanoTime()
      val activationId =
        environment.fields.get("activation_id").collect { case JsString(value) => value }.getOrElse("")
      val requestId = CxlporterContainer.requestId(activationId)
      val socket = new Socket()

      try {
        socket.connect(
          new InetSocketAddress(endpointHost, endpointPort),
          math.min(connectTimeout.toMillis, Int.MaxValue).toInt)
        socket.setSoTimeout(math.min(requestTimeout.toMillis, Int.MaxValue).toInt)
        val writer = new OutputStreamWriter(socket.getOutputStream, StandardCharsets.UTF_8)
        writer.write(s"CXLP/2 ACTIVATE $requestId $owner $function $capsuleVersion\n")
        writer.flush()
        val line =
          new BufferedReader(new InputStreamReader(socket.getInputStream, StandardCharsets.UTF_8)).readLine()
        val wallEnd = Instant.now()
        val adapterTotal = System.nanoTime() - monotonicStart
        val parsed = CxlporterContainer.parseResponse(line)
        val fields = parsed._2.map { case (key, value) => key -> JsString(value) } ++ Map(
          "openwhisk_source_integrated" -> JsBoolean(true),
          "openwhisk_activation_id" -> JsString(activationId),
          "openwhisk_cxlp_request_id" -> JsString(requestId),
          "openwhisk_adapter_total_ns" -> JsString(adapterTotal.toString),
          "cxlfork_owner" -> JsString(owner),
          "cxlfork_function" -> JsString(function),
          "cxlfork_version" -> JsString(capsuleVersion))
        val withProof = parsed._2.get("output_hex").flatMap(CxlporterContainer.decodeHex) match {
          case Some(proof) => fields + ("runtime_proof" -> JsString(proof))
          case None        => fields
        }
        val response =
          if (parsed._1) ActivationResponse.success(Some(JsObject(withProof)))
          else ActivationResponse.applicationError(JsObject(withProof))
        (Interval(wallStart, wallEnd), response)
      } catch {
        case error: Throwable =>
          val wallEnd = Instant.now()
          val payload = JsObject(
            "error" -> JsString(s"CXLP/2 activation failed: ${error.getMessage}"),
            "openwhisk_source_integrated" -> JsBoolean(true),
            "openwhisk_activation_id" -> JsString(activationId),
            "openwhisk_cxlp_request_id" -> JsString(requestId),
            "openwhisk_adapter_total_ns" -> JsString((System.nanoTime() - monotonicStart).toString))
          (Interval(wallStart, wallEnd), ActivationResponse.whiskError(payload))
      } finally {
        Try(socket.close())
      }
    }
  }
}

object CxlporterContainer {
  private val sequence = new AtomicLong(System.nanoTime())

  private[cxlfork] def requestId(activationId: String): String = {
    val hexadecimal = activationId.filter(_ != '-')
    if (hexadecimal.length >= 16 && hexadecimal
          .takeRight(16)
          .forall(character => Character.digit(character, 16) >= 0)) {
      Try(java.lang.Long.parseUnsignedLong(hexadecimal.takeRight(16), 16))
        .map(java.lang.Long.toUnsignedString)
        .getOrElse(java.lang.Long.toUnsignedString(sequence.incrementAndGet()))
    } else {
      java.lang.Long.toUnsignedString(sequence.incrementAndGet())
    }
  }

  private[cxlfork] def parseResponse(line: String): (Boolean, Map[String, String]) = {
    if (line == null || line.length > 32768)
      throw new IllegalArgumentException("missing or oversized CXLP/2 response")
    val words = line.trim.split(" +").toVector
    if (words.length < 2 || words.head != "CXLP/2" || (words(1) != "OK" && words(1) != "ERROR"))
      throw new IllegalArgumentException("invalid CXLP/2 response")
    val fields = words
      .drop(2)
      .map { word =>
        val separator = word.indexOf('=')
        if (separator <= 0)
          throw new IllegalArgumentException("invalid CXLP/2 response field")
        word.substring(0, separator) -> word.substring(separator + 1)
      }
      .toMap
    (words(1) == "OK" && fields.get("status").contains("0") && fields.get("verify").contains("1"), fields)
  }

  private[cxlfork] def decodeHex(value: String): Option[String] = {
    if ((value.length & 1) != 0 || !value.forall(character => Character.digit(character, 16) >= 0))
      return None
    val bytes = value.grouped(2).map(pair => Integer.parseInt(pair, 16).toByte).toArray
    Some(new String(bytes, StandardCharsets.UTF_8))
  }
}
