package ee.openeid.siva.validation;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class SignatureFile {
    private String signature;
    private List<Datafile> datafiles;
}
