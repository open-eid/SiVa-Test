package ee.openeid.siva.validation;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DataFilesReport", propOrder = {
        "dataFiles"
})
public class DataFilesReport {

    @XmlElement(name = "DataFiles", required = true)
    protected DataFilesReport.DataFiles dataFiles;

    public DataFilesReport.DataFiles getDataFiles() {
        return dataFiles;
    }

    public void setDataFiles(DataFilesReport.DataFiles value) {
        this.dataFiles = value;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
            "dataFile"
    })
    public static class DataFiles {

        @XmlElement(name = "DataFile")
        protected List<ReportDataFile> dataFile;

        public List<ReportDataFile> getDataFile() {
            if (dataFile == null) {
                dataFile = new ArrayList<ReportDataFile>();
            }
            return this.dataFile;
        }

    }
}
