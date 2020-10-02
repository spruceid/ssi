package com.spruceid;

public class ssi {
    public static native String getVersion();

    static {
        System.loadLibrary("ssi");
    }

    public static void main(String[] args) {
        String version = ssi.getVersion();
        System.out.println("Java libssi version: " + version);
    }
}
