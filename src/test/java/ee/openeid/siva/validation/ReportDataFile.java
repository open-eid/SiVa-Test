package ee.openeid.siva.validation;

import lombok.Data;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DataFile", propOrder = {
        "base64",
        "filename",
        "mimeType",
        "size"
})
@Data
public class ReportDataFile {

    @XmlElement(name = "Base64", required = true)
    protected String base64;
    @XmlElement(name = "Filename", required = true)
    protected String filename;
    @XmlElement(name = "MimeType", required = true)
    protected String mimeType;
    @XmlElement(name = "Size")
    protected long size;
}
