package vehicle;

import model.Vehicle;

import java.util.Comparator;
import java.util.List;

public class VehicleUtils {

    public static void sortByPrice(List<Vehicle> vehicles){
        vehicles.sort(Comparator.comparingInt(Vehicle::getPrice));
    }

    public static void sortByModel(List<Vehicle> vehicles){
        vehicles.sort(Comparator.comparing(Vehicle::model));
    }
}
