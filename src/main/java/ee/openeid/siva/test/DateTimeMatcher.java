/*
 * Copyright 2018 - 2024 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

import java.time.ZonedDateTime;

public class DateTimeMatcher extends TypeSafeMatcher<String> {

    private final ZonedDateTime beforeDateTime;

    public DateTimeMatcher(ZonedDateTime beforeDateTime) {
        this.beforeDateTime = beforeDateTime.withNano(0);
    }

    @Override
    protected boolean matchesSafely(String target) {
        ZonedDateTime targetDateTime = ZonedDateTime.parse(target);
        return targetDateTime.isEqual(beforeDateTime) || targetDateTime.isAfter(beforeDateTime);
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("date after '" + beforeDateTime + "'");
    }

    public static Matcher<String> isEqualOrAfter(ZonedDateTime beforeDateTime) {
        return new DateTimeMatcher(beforeDateTime);
    }
}
