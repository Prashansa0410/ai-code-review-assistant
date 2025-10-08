package model;

import vehicle.Drivable;
import vehicle.Vehicle;

class Car extends Vehicle implements Drivable {

    Car(String type) {
        this.type = type;
    }

    public void gear() {
        System.out.println("put gear car");
    }


    public void accelarate() {
        System.out.println("accelerate the car");
    }

    public void start() {
        System.out.println("car started");
    }

    @Override
    public void stop() {
        System.out.println("car stopped");
    }

    @Override
    public String toString() {
        return "Car::->" + super.toString();
    }

    @Override
    public void drive() {
        System.out.println("Car driving");
    }
}
