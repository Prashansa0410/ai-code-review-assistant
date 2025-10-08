package model;

import vehicle.Drivable;
import vehicle.Vehicle;

class Motorcycle extends Vehicle implements Drivable {

    Motorcycle(String type) {
        this.type = type;
    }

    @Override
    public void drive() {
        System.out.println("motorcycle driving");
    }

    public void gear() {
        System.out.println("put gear motorcycle");
    }

    public void accelarate() {
        System.out.println("accelerate the motorcycle");
    }

    @Override
    public void start() {
        System.out.println("motorcycle started");
    }

    @Override
    public void stop() {
        System.out.println("motorcycle sopeed");
    }

    @Override
    public String toString() {
        return "Motorcyle::" + super.toString();
    }


}
