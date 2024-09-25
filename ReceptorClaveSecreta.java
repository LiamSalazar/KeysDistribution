package DistribucionClaves;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import Seguridad.RSACriptografo;
import Seguridad.Comunicacion;
import Seguridad.Conexiones;
import Seguridad.Adendum;
import Chat.ChatStarter;

public class ReceptorClaveSecreta {
    private final String SERVER_ADDRESS = "localhost";
    private final int SERVER_PORT = 5000;
    private PrivateKey llave_privada_receptor;
    private PublicKey llave_publica_emisor;
    private int puertoEscuchaClave = 6000;

    private void solicitarClave(String identidad, String solicitud, String identidadObjetivo)
            throws IOException, ClassNotFoundException {
        Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

        objectOutputStream.writeObject(identidad);
        objectOutputStream.writeObject(solicitud);

        if ("solicitud_clave_publica".equals(solicitud)) {
            objectOutputStream.writeObject(identidadObjetivo);
        }

        Object respuesta = objectInputStream.readObject();

        if (respuesta instanceof Key) {
            Key clave = (Key) respuesta;
            System.out.println("Clave recibida: " + clave.toString());

            if ("solicitud_clave_privada".equals(solicitud)) {
                llave_privada_receptor = (PrivateKey) clave;
            } else if ("solicitud_clave_publica".equals(solicitud)) {
                llave_publica_emisor = (PublicKey) clave;
            }
        } else {
            System.out.println("Respuesta desconocida");
        }

        objectInputStream.close();
        objectOutputStream.close();
        socket.close();
    }

    public static void main(String[] args) {
        try {
            ReceptorClaveSecreta receptor = new ReceptorClaveSecreta();
            receptor.solicitarClave("receptor", "solicitud_clave_privada", null);
            receptor.solicitarClave("receptor", "solicitud_clave_publica", "emisor");

            System.out.println("Llave Privada del Receptor: "
                    + Base64.getEncoder().encodeToString(receptor.llave_privada_receptor.getEncoded()));
            System.out.println("Llave Pública del Emisor: "
                    + Base64.getEncoder().encodeToString(receptor.llave_publica_emisor.getEncoded()));

            System.out.println("Apertura de socket de escucha");

            ServerSocket serverSocket = new ServerSocket(receptor.puertoEscuchaClave);
            System.out.println("-------------------------------------");
            System.out.println("Esperando conexión del emisor...");
            System.out.println("-------------------------------------");
            Socket socket = serverSocket.accept();

            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            // Recepción de la clave secreta
            String claveSecretaCifrada = (String) objectInputStream.readObject();
            System.out.println("Clave secreta recibida del emisor: " + claveSecretaCifrada);

            // Recibir adendum cifrado del emisor
            String adendumCifrado = (String) objectInputStream.readObject();
            System.out.println("Adendum cifrado: " + adendumCifrado);

            objectInputStream.close();
            socket.close();
            serverSocket.close();

            // Procesar los datos recibidos
            RSACriptografo RSACriptografo = new RSACriptografo("RSA");
            String claveSecreta = RSACriptografo.descifrarString(claveSecretaCifrada, receptor.llave_privada_receptor);
            System.out.println("Clave secreta: " + claveSecreta);

            byte adendum_clave_secreta = Adendum.obtenerAdendumClave(claveSecreta);
            System.out.println("\nPrimer condicion:");
            System.out.println("Adendum clave recibida: " + adendum_clave_secreta);

            byte adendumDescifrado = Adendum.descifrarAdendum(adendumCifrado, receptor.llave_publica_emisor);
            System.out.println("Segunda condicion:");
            System.out.println("Adendum descifrado: " + adendumDescifrado);

            System.out.println("-------------------------------------");
            System.out.println("Comprobación de adendum para intercambio seguro.");
            System.out.println("-------------------------------------");

            if (adendumDescifrado == adendum_clave_secreta) {
                ServerSocket serverSocketChat = new ServerSocket(6000);
                System.out.println("Esperando conexión del emisor en el puerto 6000...");
                Socket socketChat = serverSocketChat.accept();
                ChatStarter chat = new ChatStarter(socketChat, claveSecreta);
                chat.iniciarChat();
            } else {
                System.out.println("Adendum distinto, adendumDescifrado: " + adendumDescifrado);
                System.out.println("AdendumClave: " + adendum_clave_secreta);
            }

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
