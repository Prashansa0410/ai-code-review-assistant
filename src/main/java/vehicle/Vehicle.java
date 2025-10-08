package vehicle;

import model.Car;
import model.Drivable;
import model.Motorcycle;
import model.Vehicle;

import java.util.ArrayList;
import java.util.List;


class VehicleApp {
    public static void main(String[] args) {

        List<Vehicle> vehicle = new ArrayList<>();
        vehicle.add(new Car("4 wheeler"));
        vehicle.add(new Motorcycle("2 wheeler"));
        int numberPlate =1002;
        for(Vehicle v: vehicle){
            v.setNumberPlate(numberPlate++);

            if(v instanceof Car){
                v.setModel("HondaCity");
                v.setPrice(56778);
            }
            else if(v instanceof Motorcycle){
                v.setModel("tvs");
                v.setPrice(667);
            }
        }
        VehicleUtils.sortByModel(vehicle);
        System.out.println("sort by model");
        for(Vehicle v: vehicle){
            System.out.println(v.getNumberPlate());
            v.start();
            v.stop();
            System.out.println();
            System.out.println("---"+v.toString());
            if(v instanceof Drivable){
                ((Drivable) v).drive();
            }

        }


    }
}
