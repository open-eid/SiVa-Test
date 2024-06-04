/*
 * Copyright 2023 - 2024 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
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

package ee.openeid.siva.validation;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;
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
