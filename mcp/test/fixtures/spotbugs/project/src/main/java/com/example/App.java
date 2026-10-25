package com.example;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.Statement;

public class App {
    public void query(Connection c, String user) throws Exception {
        Statement s = c.createStatement();
        s.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    public byte[] hash(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public boolean same(String a, String b) {
        return a == b;
    }
}
