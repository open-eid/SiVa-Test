package ee.openeid.siva.validation;

import lombok.Data;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ValidateDocumentResponse", propOrder = {
        "validationReport",
        "validationReportSignature"
})
@Data
public class ValidateDocumentResponse {

    @XmlElement(name = "ValidationReport", required = true)
    protected String validationReport;
    @XmlElement(name = "ValidationReportSignature")
    protected String validationReportSignature;
}
