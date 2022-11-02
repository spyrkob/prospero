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

package org.wildfly.prospero.model;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;


import static org.assertj.core.api.Assertions.*;
import static org.junit.Assert.*;

@Ignore
public class ProsperoConfigTest {

    private final ProsperoConfig prosperoConfig = new ProsperoConfig(new ArrayList<>(), new ArrayList<>());

    @Test
    public void addRepositoryIgnoresChangesIfExistingRepo() throws Exception {
        prosperoConfig.addRepository(new RepositoryRef("existing", "file:///foo.bar"));

        assertFalse(prosperoConfig.addRepository(new RepositoryRef("existing", "file:///foo.bar")));

        assertThat(prosperoConfig.getRepositories()).containsExactly(
                new RepositoryRef("existing", "file:///foo.bar")
        );
    }

    @Test
    public void addRepositoryThrowsErrorIfSameIdDifferentUrl() throws Exception {
        assertTrue(prosperoConfig.addRepository(new RepositoryRef("existing", "file:///foo.bar")));

        try {
            prosperoConfig.addRepository(new RepositoryRef("existing", "file:///different.url"));
            Assert.fail("Adding repository with the same ID but different URL should fail");
        } catch (IllegalArgumentException e) {
            // OK, ignore
        }
    }

    @Test
    public void addRepositoryAddsDistinctRepository() throws Exception {
        prosperoConfig.addRepository(new RepositoryRef("existing", "file:///foo.bar"));

        assertTrue(prosperoConfig.addRepository(new RepositoryRef("test", "file:///foo.bar")));

        assertThat(prosperoConfig.getRepositories()).containsExactlyInAnyOrder(
                new RepositoryRef("existing", "file:///foo.bar"),
                new RepositoryRef("test", "file:///foo.bar")
        );
    }

    @Test
    public void addRepositoryAddsNewRepositoryToEmptyList() throws Exception {
        assertTrue(prosperoConfig.addRepository(new RepositoryRef("test", "file:///foo.bar")));

        assertThat(prosperoConfig.getRepositories()).containsExactly(
                new RepositoryRef("test", "file:///foo.bar")
        );
    }
}