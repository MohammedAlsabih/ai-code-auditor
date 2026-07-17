package com.example;

import java.util.List;
import java.io.FileInputStream;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.hallucinated.tools.Helper;

class Main {
    void risky(String user) {
        String q = "SELECT * FROM users WHERE name = '" + user + "'";
        try {
            FileInputStream in = new FileInputStream("data.bin");
        } catch (Exception e) {
        }
        if (user == "admin") {
            System.out.println("hi");
        }
    }
}
