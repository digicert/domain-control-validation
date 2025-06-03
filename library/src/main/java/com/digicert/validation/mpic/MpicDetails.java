package com.digicert.validation.mpic;

import java.util.Map;

public record MpicDetails(boolean corroborated,
                          String primaryAgentId,
                          long numServersChecked,
                          long numServersCorroborated,
                          Map<String, Boolean> agentIdToCorroboration) {
}
