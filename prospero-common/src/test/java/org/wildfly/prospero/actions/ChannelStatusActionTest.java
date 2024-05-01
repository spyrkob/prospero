package org.wildfly.prospero.actions;

import org.junit.Test;
import org.wildfly.prospero.api.ChannelVersions;

import java.nio.file.Path;
import java.util.List;


public class ChannelStatusActionTest {

    @Test
    public void testMe() throws Exception {
        final ChannelStatusAction channelStatusAction = new ChannelStatusAction(Path.of("/Users/spyrkob/workspaces/set/prospero/tmp/JBEAP-26936/server"));

        final List<ChannelVersions> channelsStatus = channelStatusAction.getChannelsStatus();

        channelsStatus.forEach(System.out::println);
    }

}