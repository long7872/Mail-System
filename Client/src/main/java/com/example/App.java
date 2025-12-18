package com.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

import com.example.enums.Screen;
import com.example.utils.UserSession;

/**
 * JavaFX App
 */
public class App extends Application {

    private static Stage stage;
    private static Scene scene;

    @Override
    public void start(Stage stage) throws IOException {
        App.stage = stage;
        UserSession.clear();
        scene = new Scene(loadFXML(Screen.AUTH.value()), 720, 480);
        stage.setScene(scene);
        stage.show();
    }

    public static void setRoot(String fxml) throws IOException {
        scene.setRoot(loadFXML(fxml));
    }

    private static Parent loadFXML(String fxml) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(App.class.getResource(fxml + ".fxml"));
        return fxmlLoader.load();
    }

    public static void switchToScene(String screenValue, String title) throws IOException {
        Scene switchScene = new Scene(loadFXML(screenValue), 720, 480);
        stage.setScene(switchScene);
        stage.setTitle(title);
    }

    public static void main(String[] args) {
        launch();
    }

}