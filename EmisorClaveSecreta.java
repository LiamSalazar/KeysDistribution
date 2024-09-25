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
import static Seguridad.Adendum.cifrarAdendum;
import static Seguridad.Adendum.obtenerAdendumClave;

public class EmisorClaveSecreta {
    private final String SERVER_ADDRESS = "localhost";
    private final int SERVER_PORT = 5000;
    static int puertoEntrada = 6000;
    private PrivateKey llave_privada_emisor;
    private PublicKey llave_publica_receptor;

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
                llave_privada_emisor = (PrivateKey) clave;
            } else if ("solicitud_clave_publica".equals(solicitud)) {
                llave_publica_receptor = (PublicKey) clave;
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
            EmisorClaveSecreta emisor = new EmisorClaveSecreta();
            emisor.solicitarClave("emisor", "solicitud_clave_privada", null);
            emisor.solicitarClave("emisor", "solicitud_clave_publica", "receptor");

            // Imprimir las claves al final del proceso
            System.out.println("Llave Privada del Emisor: "
                    + Base64.getEncoder().encodeToString(emisor.llave_privada_emisor.getEncoded()));
            System.out.println("Llave Pública del Receptor: "
                    + Base64.getEncoder().encodeToString(emisor.llave_publica_receptor.getEncoded()));

            Scanner scan = new Scanner(System.in);

            System.out.println("-------------------------------------");
            System.out.println("Ingresa la clave Secreta");

            String claveSecreta = scan.nextLine();
            System.out.println(claveSecreta);

            RSACriptografo RSACriptografo = new RSACriptografo("RSA");
            String claveSecretaCifrada = RSACriptografo.cifrarString(claveSecreta, emisor.llave_publica_receptor);
            System.out.println("clave Secreta Cifrada " + claveSecretaCifrada);

            byte adendum_clave_secreta = (obtenerAdendumClave(claveSecreta));
            System.out.println("\nadendum clave " + adendum_clave_secreta);
            String adendum_cifrado = cifrarAdendum(adendum_clave_secreta, emisor.llave_privada_emisor);
            System.out.println("adendum clave cifrado " + adendum_cifrado);

            System.out.println("-------------------------------------");
            System.out.println("Conectando con Receptor");
            System.out.println("-------------------------------------");

            try {
                Socket socket = new Socket(emisor.SERVER_ADDRESS, puertoEntrada);
                System.out.println("Conectando con el receptor...");

                // Enviar datos al Receptor
                OutputStream outputStream = socket.getOutputStream();
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

                // Envío de la clave secreta
                objectOutputStream.writeObject(claveSecretaCifrada);
                System.out.println("Clave secreta enviada al receptor.");

                // Enviar adendum cifrado al receptor
                objectOutputStream.writeObject(adendum_cifrado);
                System.out.println("Adendum cifrado enviado al receptor.");

                objectOutputStream.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            System.out.println("-------------------------------------");
            System.out.println("Esperando comprobación de adendum para intercambio seguro.");
            System.out.println("-------------------------------------");

            boolean conectado = false;
            int intentos = 0;
            int maxIntentos = 10; // Puedes ajustar el número máximo de intentos
            while (!conectado && intentos < maxIntentos) {
                try {
                    System.out.println("Intentando conectar con el receptor...");
                    Socket conexionChat = Conexiones.obtenerConexion(6000, "127.0.0.1");
                    ChatStarter chat = new ChatStarter(conexionChat, claveSecreta);
                    chat.iniciarChat();
                    conectado = true; // Si la conexión es exitosa, se sale del bucle
                } catch (ConnectException e) {
                    System.out.println("Conexión rechazada, reintentando...");
                    intentos++;
                    try {
                        Thread.sleep(1000); // Espera 2 segundos antes de reintentar
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt(); // Restablece el estado de interrupción
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    break; // Si ocurre otro tipo de IOException, salir del bucle
                }
            }

            if (!conectado) {
                System.out.println("No se pudo establecer conexión después de " + maxIntentos
                        + " intentos, la conexión es muy lenta.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
