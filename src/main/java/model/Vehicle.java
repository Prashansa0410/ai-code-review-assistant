package model;
abstract class Vehicle {
    private String model;
    String type;
    private int numberPlate;
    private int price;

    public abstract void start();

    public abstract void stop();

    public void setNumberPlate(int numberPlate){
        this.numberPlate = numberPlate;
    }
    public int getNumberPlate(){
        return numberPlate;
    }

    int getPrice(){
        return price;
    }

    public void setModel(String model){
        this.model=model;
    }

    public void setPrice(int price){
        this.price = price;
    }



    String model(){
        return model;
    }

    public String toString(){
        return "model::"+model+" ,type::"+type+" ,numberPlate::"+numberPlate+" ,price::"+price;
    }
}
