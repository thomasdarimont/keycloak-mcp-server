package com.github.thomasdarimont.keycloak.mcp.backend.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Which {@code Mcp-Param-*} values pass: the cases of the header standardization. */
class McpParamHeaderCheckTest {

    @Test
    void plainValuesAndValidBase64Pass() {
        assertTrue(McpParamHeaderCheck.decodable("us-west1"));
        assertTrue(McpParamHeaderCheck.decodable(""));
        assertTrue(McpParamHeaderCheck.decodable("=?base64?SGVsbG8=?="));
        assertTrue(McpParamHeaderCheck.decodable("=?base64??="), "an empty value");
        // without the exact markers a value is a literal, not Base64
        assertTrue(McpParamHeaderCheck.decodable("SGVsbG8"));
        assertTrue(McpParamHeaderCheck.decodable("=?base64?SGVsbG8"));
        assertTrue(McpParamHeaderCheck.decodable("=?BASE64?SGVsbG8?="));
    }

    @Test
    void base64ThatCannotBeDecodedIsRefused() {
        assertFalse(McpParamHeaderCheck.decodable("=?base64?SGVsbG8?="), "padding missing");
        assertFalse(McpParamHeaderCheck.decodable("=?base64?SGVs!!!bG8=?="), "outside the alphabet");
    }
}
