/*
 * Copyright 2024 - 2024 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence")
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is
 * distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package ee.openeid.siva.test.getDataFiles

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import spock.lang.Ignore

import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/use_cases/#ddoc-data-file-extraction-process")
class DdocGetDataFilesSpec extends GenericSpecification {

    @Description("Requesting data files from valid DDOC with data file returns data file")
    def "Given valid DDOC, then data files request returns data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("18912.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("readme"))
                .body("dataFiles[0].mimeType", is("text/plain"))
                .body("dataFiles[0].base64", startsWith("RGlnaURvYyBpcyBhIGdlbmVyaWMgbGlicmFyeSBp"))
                .body("dataFiles[0].size", is(491))
    }

    @Description("Requesting data files from invalid DDOC with data file returns data file")
    def "Given invalid DDOC, then data files request returns data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("OCSP nonce vale.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("testfail.txt"))
                .body("dataFiles[0].mimeType", is("text/plain"))
                .body("dataFiles[0].base64", is("T2xlbiB0ZXN0IGZhaWwu"))
                .body("dataFiles[0].size", is(15))
    }

    @Description("Requesting data files from DDOC with xml v1.0 returns data file")
    def "Given DDOC with xml v1.0, then data files request returns data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("SK-XML1.0.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("Tartu ja Tallinna koostooleping.doc"))
                .body("dataFiles[0].mimeType", is("application/msword"))
                .body("dataFiles[0].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAUgAAAAAAAAAA"))
                .body("dataFiles[0].size", is(44544))
    }

    @Description("Requesting data files from DDOC with xml v1.1 returns data file")
    def "Given DDOC with xml v1.1, then data files request returns data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("DIGIDOC-XML1.1.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("puhkus_urmo_062006.doc"))
                .body("dataFiles[0].mimeType", is("application/msword"))
                .body("dataFiles[0].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAAJAAAA"))
                .body("dataFiles[0].size", is(549376))
    }

    @Description("Requesting data files from DDOC with xml v1.2 returns data file")
    def "Given DDOC with xml v1.2, then data files request returns data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("DIGIDOC-XML1.2.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("RO219559508.pdf"))
                .body("dataFiles[0].mimeType", is("text/text"))
                .body("dataFiles[0].base64", startsWith("JVBERi0xLjMKJeLjz9MKMSAwIG9iajw8L1Byb2R1Y2VyKGh0bWxkb2MgMS44LjIzIENvcHlyaWdodCAxOTk3LTIwMDI"))
                .body("dataFiles[0].size", is(3938))
    }

    @Description("Requesting data files from DDOC with xml v1.3 returns data file")
    def "Given DDOC with xml v1.3, then data files request returns data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("valid_XML1_3.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("test.txt"))
                .body("dataFiles[0].mimeType", is("application/octet-stream"))
                .body("dataFiles[0].base64", startsWith("VGVzdCBhbmQgc29tZSBvdGhlciB0ZXN0"))
                .body("dataFiles[0].size", is(24))
    }

    @Ignore("SIVA-376")
    @Description("Requesting data files from hashcoded DDOC returns null as data file")
    def "Given hashcoded DDOC, then data files request returns null for data file"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("DIGIDOC-XML1.3_hashcode.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("Glitter-rock-4_gallery.jpg"))
                .body("dataFiles[0].mimeType", is("application/octet-stream"))
                .body("dataFiles[0].base64", nullValue())
                .body("dataFiles[0].size", is(41114))
    }

    @Description("Requesting data files from DDOC with 12 different files of different types returns data files")
    def "Given DDOC with multiple different files, then data files request returns data files"() {
        expect:
        SivaRequests.getDataFiles(RequestData.dataFileRequestFromFile("igasugust1.3.ddoc"))
                .then()
                .body("dataFiles[0].filename", is("DigiDocService_spec_1_110_est.pdf"))
                .body("dataFiles[0].mimeType", is("application/pdf"))
                .body("dataFiles[0].base64", startsWith("JVBERi0xLjMKJcfsj6IKOCAwIG9iago8PC9MZW5ndGggOSAwIFIvRmlsdGVyIC9G"))
                .body("dataFiles[0].size", is(435164))
                .body("dataFiles[1].filename", is("Testilood20070320.doc"))
                .body("dataFiles[1].mimeType", is("application/msword"))
                .body("dataFiles[1].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAAEAAAA"))
                .body("dataFiles[1].size", is(222720))
                .body("dataFiles[2].filename", is("fail.rtf"))
                .body("dataFiles[2].mimeType", is("application/msword"))
                .body("dataFiles[2].base64", startsWith("e1xydGYxXGFuc2lcZGVmZjBcYWRlZmxhbmcxMDI1CntcZm9udHRibHtcZjBcZnJv"))
                .body("dataFiles[2].size", is(2145))
                .body("dataFiles[3].filename", is("fail.odt"))
                .body("dataFiles[3].mimeType", is("application/unknown"))
                .body("dataFiles[3].base64", startsWith("UEsDBBQAAAAAAJhRwTpexjIMJwAAACcAAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlv"))
                .body("dataFiles[3].size", is(7427))
                .body("dataFiles[4].filename", is("4.txt"))
                .body("dataFiles[4].mimeType", is("text/plain"))
                .body("dataFiles[4].base64", startsWith("/GtzZmFpbA=="))
                .body("dataFiles[4].size", is(7))
                .body("dataFiles[5].filename", is("kolm.doc"))
                .body("dataFiles[5].mimeType", is("application/msword"))
                .body("dataFiles[5].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[5].size", is(24064))
                .body("dataFiles[6].filename", is("5.xls"))
                .body("dataFiles[6].mimeType", is("application/vnd.ms-excel"))
                .body("dataFiles[6].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[6].size", is(14848))
                .body("dataFiles[7].filename", is("kaks.doc"))
                .body("dataFiles[7].mimeType", is("application/msword"))
                .body("dataFiles[7].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[7].size", is(24064))
                .body("dataFiles[8].filename", is("kõõs.txt"))
                .body("dataFiles[8].mimeType", is("text/plain"))
                .body("dataFiles[8].base64", is("bfZoaGho"))
                .body("dataFiles[8].size", is(6))
                .body("dataFiles[9].filename", is("yks.doc"))
                .body("dataFiles[9].mimeType", is("application/msword"))
                .body("dataFiles[9].base64", startsWith("0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAA"))
                .body("dataFiles[9].size", is(24064))
                .body("dataFiles[10].filename", is("testid.txt"))
                .body("dataFiles[10].mimeType", is("text/plain"))
                .body("dataFiles[10].base64", startsWith("UElOMSBibG9raXM6DQoNCjI1MTMNCjI1MjMNCjI1MjcNCjI1MzENCjI1NTkNCj"))
                .body("dataFiles[10].size", is(414))
                .body("dataFiles[11].filename", is("NsPdf.PDF"))
                .body("dataFiles[11].mimeType", is("application/pdf"))
                .body("dataFiles[11].base64", startsWith("JVBERi0xLjMKJeTjz9IKNSAwIG9iago8PC9MZW5ndGggNiAwIFIKL0ZpbHRlci9GbGF0ZURlY29"))
                .body("dataFiles[11].size", is(2783))
    }
}
