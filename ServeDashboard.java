import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ServeDashboard {
    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8000;
        Path root = Paths.get(args.length > 1 ? args[1] : "dashboard").toAbsolutePath().normalize();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", exchange -> {
            String reqPath = exchange.getRequestURI().getPath();
            if (reqPath.equals("/")) reqPath = "/index.html";
            Path file = root.resolve(reqPath.substring(1)).normalize();

            if (!file.startsWith(root) || !Files.isRegularFile(file)) {
                byte[] msg = "404 Not Found".getBytes();
                exchange.sendResponseHeaders(404, msg.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(msg);
                }
                return;
            }

            String name = file.getFileName().toString().toLowerCase();
            String mime = name.endsWith(".html") ? "text/html; charset=utf-8"
                        : name.endsWith(".css")  ? "text/css; charset=utf-8"
                        : name.endsWith(".js")   ? "application/javascript; charset=utf-8"
                        : name.endsWith(".json") ? "application/json; charset=utf-8"
                        : "application/octet-stream";

            byte[] bytes = Files.readAllBytes(file);
            exchange.getResponseHeaders().set("Content-Type", mime);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        server.start();
        System.out.println("CyberSec Spark SIEM Dashboard running at http://localhost:" + port + "/");
    }
}
