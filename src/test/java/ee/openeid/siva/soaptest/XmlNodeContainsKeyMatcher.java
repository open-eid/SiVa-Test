/*
 * Copyright 2020 - 2023 Riigi Infosüsteemide Amet
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

package ee.openeid.siva.soaptest;

import io.restassured.internal.path.xml.NodeChildrenImpl;
import io.restassured.path.xml.element.Node;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

import static java.util.Objects.requireNonNull;

public class XmlNodeContainsKeyMatcher extends TypeSafeMatcher<NodeChildrenImpl> {

    private final String key;

    public XmlNodeContainsKeyMatcher(String key) {
        this.key = requireNonNull(key);
    }

    @Override
    protected boolean matchesSafely(NodeChildrenImpl nodeChildren) {
        if (nodeChildren.isEmpty()) {
            return false;
        }

        for (Node node : nodeChildren.nodeIterable()) {
            if (!containsKey(node)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsKey(Node node) {
        for (Node nodeKey : node.children().nodeIterable()) {
            if (key.equals(nodeKey.name())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(String.format("Expected key [%s] to be present, but not found", key));
    }
}
