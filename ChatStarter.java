package Chat;

import Seguridad.Comunicacion;

import java.io.*;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * ChatStarter con benchmark de RTT cifrado.
 * - Receptor: eco automático de mensajes "PING_*" (reenviando MISMO
 * ciphertext).
 * - Emisor: comando "/bench N" -> mide mean y p95 del RTT cifrado (ms).
 */
public class ChatStarter {
    Socket conexionEntrada;
    PrintWriter printWriter;
    BufferedReader bufferedReader;
    private AESCriptografo criptografo;
    String claveSecreta;

    // Flag para pausar el hilo receptor durante el benchmark y evitar competencia
    // por el socket
    private final AtomicBoolean benchMode = new AtomicBoolean(false);

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
                    if (mensaje == null || mensaje.equalsIgnoreCase("salir"))
                        break;

                    // Comando: /bench N (por defecto N=100)
                    if (mensaje.startsWith("/bench")) {
                        ejecutarBenchmark(mensaje);
                        continue; // no enviar el comando como mensaje normal
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
                    // Pausa de lectura si estamos en benchmark local
                    if (benchMode.get()) {
                        try {
                            Thread.sleep(5);
                        } catch (InterruptedException ignored) {
                        }
                        continue;
                    }

                    String mensajeCifradoRecibido = Comunicacion.recibirMensaje(this.bufferedReader);
                    if (mensajeCifradoRecibido == null || mensajeCifradoRecibido.isEmpty())
                        break;

                    String mensajeDescifrado = null;
                    try {
                        mensajeDescifrado = this.criptografo.desencriptarMensaje(mensajeCifradoRecibido);
                    } catch (Exception e) {
                        System.out.println("[Chat] Mensaje corrupto/no descifrable (ignorado).");
                    }

                    // ECO inmediato si es un PING_*
                    if (mensajeDescifrado != null && mensajeDescifrado.startsWith("PING_")) {
                        Comunicacion.enviarMensaje(mensajeCifradoRecibido, this.printWriter); // reenvía MISMO
                                                                                              // ciphertext
                        continue; // no ensuciamos consola con los pings
                    }

                    if (mensajeDescifrado != null)
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
            // no unimos al receptor para permitir fin limpio tras "salir"
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    // ==========================
    // Benchmark de RTT cifrado
    // ==========================
    private void ejecutarBenchmark(String comando) {
        int iterations = 100;
        try {
            String[] parts = comando.trim().split("\\s+");
            if (parts.length >= 2)
                iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException ignored) {
        }

        List<Long> rtts = new ArrayList<>(iterations);
        benchMode.set(true); // pausamos el hilo receptor local

        // Warm-up opcional
        try {
            String warmC = criptografo.encriptarMensaje("PING_WARMUP");
            Comunicacion.enviarMensaje(warmC, printWriter);
            String echoC = Comunicacion.recibirMensaje(bufferedReader);
            if (echoC != null)
                criptografo.desencriptarMensaje(echoC); // validar
        } catch (Exception e) {
            System.out.println("[Bench] Warm-up falló (continuando): " + e.getMessage());
        }

        for (int i = 0; i < iterations; i++) {
            String msg = "PING_" + i;
            try {
                String c = criptografo.encriptarMensaje(msg);
                long t0 = System.nanoTime();
                Comunicacion.enviarMensaje(c, printWriter);

                // Espera el ECO con el mismo contenido en claro
                while (true) {
                    String echoC = Comunicacion.recibirMensaje(bufferedReader);
                    if (echoC == null)
                        throw new RuntimeException("Conexión cerrada durante benchmark.");
                    String echo = criptografo.desencriptarMensaje(echoC);
                    if (msg.equals(echo)) {
                        long t1 = System.nanoTime();
                        rtts.add((t1 - t0) / 1_000_000L); // ms
                        break;
                    }
                    // Si llega algo que no es el eco, lo ignoramos durante el bench
                }
            } catch (Exception e) {
                System.out.println("[Bench] Iteración " + i + " falló: " + e.getMessage());
            }
        }

        benchMode.set(false); // reanudamos receptor

        double meanMs = mean(rtts);
        double p95Ms = p95(rtts);
        System.out.printf("[Bench] %d iters -> Mean RTT: %.2f ms | p95: %.2f ms%n", rtts.size(), meanMs, p95Ms);

        // (Opcional) CSV
        // saveCsv("chat_rtt.csv", rtts);
    }

    // ==========================
    // Utilidades estadísticas
    // ==========================
    private static double mean(List<Long> xs) {
        if (xs == null || xs.isEmpty())
            return 0.0;
        long sum = 0;
        for (long v : xs)
            sum += v;
        return (sum * 1.0) / xs.size();
    }

    private static double p95(List<Long> xs) {
        if (xs == null || xs.isEmpty())
            return 0.0;
        List<Long> copy = new ArrayList<>(xs);
        Collections.sort(copy);
        int idx = (int) Math.ceil(0.95 * copy.size()) - 1;
        if (idx < 0)
            idx = 0;
        if (idx >= copy.size())
            idx = copy.size() - 1;
        return copy.get(idx);
    }

    @SuppressWarnings("unused")
    private static void saveCsv(String filename, List<Long> rtts) {
        try (PrintWriter pw = new PrintWriter(filename)) {
            pw.println("iter,rtt_ms");
            for (int i = 0; i < rtts.size(); i++)
                pw.println(i + "," + rtts.get(i));
            System.out.println("[Bench] Guardado: " + filename);
        } catch (Exception e) {
            System.out.println("[Bench] CSV no pudo guardarse: " + e.getMessage());
        }
    }
}
