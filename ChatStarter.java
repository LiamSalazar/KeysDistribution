package Chat;

import Seguridad.Comunicacion;

import java.io.*;
import java.net.Socket;
import java.util.Scanner;

public class ChatStarter {
    Socket conexionEntrada;
    PrintWriter printWriter;
    BufferedReader bufferedReader;
    private AESCriptografo criptografo;
    String claveSecreta;

    public ChatStarter(Socket conexionEntrada, String claveSecreta) throws Exception {
        this.claveSecreta = claveSecreta;
        this.conexionEntrada = conexionEntrada;
        this.printWriter = new PrintWriter(conexionEntrada.getOutputStream());
        this.bufferedReader = new BufferedReader(new InputStreamReader(conexionEntrada.getInputStream()));
        this.criptografo = new AESCriptografo(claveSecreta);
    }

    public void iniciarChat() throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("----------------CHAT INICIALIZADO----------------");
        System.out.println("Clave Secreta: " + claveSecreta);
        System.out.println("-------------------------------------------------");

        Thread enviarThread = new Thread(() -> {
            try {
                while (true) {
                    String mensaje = scanner.nextLine();
                    if (mensaje.equalsIgnoreCase("salir")) {
                        break;
                    }
                    String mensajeCifrado = this.criptografo.encriptarMensaje(mensaje);
                    Comunicacion.enviarMensaje(mensajeCifrado, this.printWriter);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        Thread recibirThread = new Thread(() -> {
            try {
                while (true) {
                    String mensajeCifradoRecibido = Comunicacion.recibirMensaje(this.bufferedReader);
                    if (mensajeCifradoRecibido == null || mensajeCifradoRecibido.isEmpty()) {
                        break; // Se ha desconectado el cliente
                    }
                    String mensajeDescifrado = this.criptografo.desencriptarMensaje(mensajeCifradoRecibido);
                    System.out.println(mensajeDescifrado);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        enviarThread.start();
        recibirThread.start();

        try {
            enviarThread.join();
            recibirThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
