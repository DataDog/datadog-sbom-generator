package com.sample;

import org.example.Greeter;

public class ExampleApp {
  public static void main(String[] args) {
    try {
      Greeter greeter = new Greeter("Daniel");
      greeter.sayHello();
    } catch (Exception e ) {
      System.err.println("Greeting failed: " + e.getMessage());
    }
  }
}
