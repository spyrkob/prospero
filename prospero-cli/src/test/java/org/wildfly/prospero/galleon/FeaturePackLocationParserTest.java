/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.prospero.galleon;

import org.jboss.galleon.universe.FeaturePackLocation;
import org.jboss.galleon.universe.maven.MavenUniverseException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class FeaturePackLocationParserTest {

    @Test
    public void useProvidedGavWhenUsedFull() throws Exception {
        final FeaturePackLocation resolvedFpl = resolveFplVersion("org.wildfly:wildfly-ee-galleon-pack:26.0.0.Final");
        assertEquals("26.0.0.Final", resolvedFpl.getBuild());
        assertEquals("org.wildfly:wildfly-ee-galleon-pack::zip", resolvedFpl.getProducerName());
    }

    @Test
    public void useUniverseIfProvided() throws Exception {
        assertEquals(null, resolveFplVersion("wildfly@maven(community-universe):current").getBuild());
        assertEquals("current", resolveFplVersion("wildfly@maven(community-universe):current").getChannelName());
    }

    @Test(expected = IllegalArgumentException.class)
    public void requireGroupAndArtifactIds() throws Exception {
        resolveFplVersion("illegalname");
    }

    private FeaturePackLocation resolveFplVersion(String fplText) throws MavenUniverseException {
        return FeaturePackLocationParser.resolveFpl(fplText);
    }
}