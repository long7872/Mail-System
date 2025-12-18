module com.example {
    requires javafx.controls;
    requires javafx.fxml;
    requires transitive javafx.graphics;
    requires java.net.http;
    requires org.json;

    opens com.example.controller to javafx.fxml;
    exports com.example.controller;

    opens com.example to javafx.graphics;
    exports com.example;
}
