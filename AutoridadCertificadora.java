package DistribucionClaves;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class AutoridadCertificadora {
    private ServerSocket serverSocket;
    private HashMap<String, KeyPair> keyPairs;
    private final int PORT = 5000;

    public AutoridadCertificadora() throws NoSuchAlgorithmException, IOException {
        this.keyPairs = new HashMap<>();
        this.serverSocket = new ServerSocket(PORT);
        System.out.println("Autoridad Certificadora iniciada en el puerto " + PORT);
    }

    private void generarClaveRSA(String identidad) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.keyPairs.put(identidad, keyPair);
    }

    private void atenderSolicitud(Socket clientSocket)
            throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());

        String identidad = (String) objectInputStream.readObject();
        String solicitud = (String) objectInputStream.readObject();

        if (!this.keyPairs.containsKey(identidad)) {
            generarClaveRSA(identidad);
        }

        if ("solicitud_clave_privada".equals(solicitud)) {
            KeyPair keyPair = this.keyPairs.get(identidad);
            objectOutputStream.writeObject(keyPair.getPrivate());
        } else if ("solicitud_clave_publica".equals(solicitud)) {
            String identidadObjetivo = (String) objectInputStream.readObject();
            if (!this.keyPairs.containsKey(identidadObjetivo)) {
                generarClaveRSA(identidadObjetivo);
            }
            KeyPair keyPairObjetivo = this.keyPairs.get(identidadObjetivo);
            objectOutputStream.writeObject(keyPairObjetivo.getPublic());
        }

        objectInputStream.close();
        objectOutputStream.close();
        clientSocket.close();
    }

    public void iniciarServicio() throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        while (true) {
            Socket clientSocket = serverSocket.accept();
            atenderSolicitud(clientSocket);
        }
    }

    public static void main(String[] args) {
        try {
            AutoridadCertificadora ac = new AutoridadCertificadora();
            ac.iniciarServicio();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
