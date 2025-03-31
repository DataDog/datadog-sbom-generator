package reachability

var fileContent = []byte(`
package com.example;

import org.springframework.remoting.rmi.CodebaseAwareObjectInputStream;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;


public class InsecureDeserializationExample {

    public static void main(String[] args) {
        try {
            // Serialize a trusted object (e.g., an ArrayList)
            byte[] safeSerializedData = serializeTrustedObject();

            Object deserializedObject = deserialize(safeSerializedData);

            System.out.println("Successfully deserialized!");
            System.out.println(deserializedObject);
        } catch (Exception e) {
            System.err.println("Deserialization failed: " + e.getMessage());
        }

        try {
            // Serialize a trusted object (e.g., an ArrayList)
            byte[] safeSerializedData = serializeHarmfulObject();

            Object deserializedObject = deserialize(safeSerializedData);

            System.out.println("Successfully deserialized!");
            System.out.println(deserializedObject);
        } catch (Exception e) {
            System.err.println("Deserialization failed: " + e.getMessage());
        }
    }

    private static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (
						ByteArrayInputStream bis = new ByteArrayInputStream(data);
            CodebaseAwareObjectInputStream ois = new CodebaseAwareObjectInputStream(bis, (String) null)
						CodebaseAwareObjectInputStream ois2 = new org.springframework.remoting.rmi.CodebaseAwareObjectInputStream(bis, (String) null)
				) {
            // Validate object type before casting
            Object obj = ois.readObject();
            return obj;
				}
    }


    private static byte[] serializeTrustedObject() throws IOException {
        List<String> list = new ArrayList<>();
        list.add("Item 1");
        list.add("Item 2");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(list);
        }
        return bos.toByteArray();
    }

    private static byte[] serializeHarmfulObject() throws IOException {
        Shell sh = new Shell();
        // List<String> sh = new ArrayList<>();
        // String sh = "weqwe\n\n";

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(sh);
        }
        return bos.toByteArray();
    }
}
`)
