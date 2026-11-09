package com.burnbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "management.server.port=")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ActuatorHealthTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("AC-001, AC-003, AC-006 & AC-007: Actuator health endpoint retorna UP con componentes key y jobs sin fugar secretos")
    void healthEndpointReturnsUp() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components.key.status").value("UP"))
                .andExpect(jsonPath("$.components.key.details.active_version").exists())
                .andExpect(jsonPath("$.components.key.details.kek").doesNotExist())
                .andExpect(jsonPath("$.components.jobs.status").value("UP"))
                .andExpect(jsonPath("$.components.jobs.details.recent_runs_count").exists());
    }

    @Test
    @DisplayName("AC-005: Actuator info endpoint responde 200")
    void infoEndpointReturnsOk() throws Exception {
        mockMvc.perform(get("/actuator/info"))
                .andExpect(status().isOk());
    }
}
