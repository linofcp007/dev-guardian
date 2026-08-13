package com.example.orders;

// Fixture for guardian-import-java's static and wildcard forms, neither of
// which OrderController.java exercises (it only uses plain imports).
import static java.util.Collections.emptyList;
import com.example.orders.internal.*;

final class OrderDefaults {
    static Object empty() {
        return emptyList();
    }
}
