package ee.openeid.siva.validation;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class Datafile {

    private String filename;
    private String hashAlgo;
    private String hash;
}
