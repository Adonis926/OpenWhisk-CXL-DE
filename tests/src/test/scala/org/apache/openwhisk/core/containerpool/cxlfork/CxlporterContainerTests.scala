/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0.
 */

package org.apache.openwhisk.core.containerpool.cxlfork

import org.junit.runner.RunWith
import org.scalatest.{FlatSpec, Matchers}
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class CxlporterContainerTests extends FlatSpec with Matchers {

  behavior of "CxlporterContainer CXLP/2 adapter"

  it should "derive a stable unsigned request id from an OpenWhisk activation id" in {
    CxlporterContainer.requestId("0000000000000000000000000000002a") shouldBe "42"
    CxlporterContainer.requestId("0000000000000000ffffffffffffffff") shouldBe "18446744073709551615"
  }

  it should "accept only a verified successful CXLP/2 response" in {
    val (verified, fields) =
      CxlporterContainer.parseResponse("CXLP/2 OK status=0 verify=1 output_hex=6f6b")

    verified shouldBe true
    fields("status") shouldBe "0"
    fields("verify") shouldBe "1"
    CxlporterContainer.decodeHex(fields("output_hex")) shouldBe Some("ok")
  }

  it should "preserve a well-formed remote error without treating it as success" in {
    val (verified, fields) =
      CxlporterContainer.parseResponse("CXLP/2 ERROR status=-2 verify=0 error_stage=catalog_lookup")

    verified shouldBe false
    fields("status") shouldBe "-2"
    fields("error_stage") shouldBe "catalog_lookup"
  }

  it should "not treat an incomplete OK response as verified" in {
    val (verified, _) = CxlporterContainer.parseResponse("CXLP/2 OK status=0")
    verified shouldBe false
  }

  it should "reject the legacy protocol and malformed fields" in {
    an[IllegalArgumentException] should be thrownBy
      CxlporterContainer.parseResponse("CXLP/1 RESULT status=0 verify=1")
    an[IllegalArgumentException] should be thrownBy
      CxlporterContainer.parseResponse("CXLP/2 OK status=0 malformed")
  }

  it should "reject missing and oversized responses" in {
    an[IllegalArgumentException] should be thrownBy CxlporterContainer.parseResponse(null)
    an[IllegalArgumentException] should be thrownBy
      CxlporterContainer.parseResponse("X" * 32769)
  }

  it should "reject malformed hexadecimal runtime proof" in {
    CxlporterContainer.decodeHex("0") shouldBe None
    CxlporterContainer.decodeHex("zz") shouldBe None
  }
}
