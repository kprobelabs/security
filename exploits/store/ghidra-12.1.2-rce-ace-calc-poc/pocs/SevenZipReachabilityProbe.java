import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import net.sf.sevenzipjbinding.IInArchive;
import net.sf.sevenzipjbinding.PropID;
import net.sf.sevenzipjbinding.SevenZip;
import net.sf.sevenzipjbinding.impl.RandomAccessFileInStream;

public final class SevenZipReachabilityProbe {
    private SevenZipReachabilityProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path zipPath = Files.createTempFile("ghidra-sevenzip-safe-", ".zip");
        createHarmlessZip(zipPath);

        System.out.println("Purpose: benign SevenZipJBinding runtime reachability check.");
        System.out.println("Sample: " + zipPath);
        System.out.println("No malicious archive bytes or command payload are present.");

        SevenZip.initSevenZipFromPlatformJAR();
        System.out.println("SevenZip version object: " + SevenZip.getSevenZipVersion());

        try (RandomAccessFile file = new RandomAccessFile(zipPath.toFile(), "r");
                IInArchive archive = SevenZip.openInArchive(null, new RandomAccessFileInStream(file))) {
            System.out.println("Archive format: " + archive.getArchiveFormat());
            System.out.println("Item count: " + archive.getNumberOfItems());
            for (int i = 0; i < archive.getNumberOfItems(); i++) {
                System.out.println("Item " + i + " path: " + archive.getProperty(i, PropID.PATH));
            }
        }
    }

    private static void createHarmlessZip(Path zipPath) throws Exception {
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(zipPath))) {
            ZipEntry entry = new ZipEntry("hello.txt");
            zip.putNextEntry(entry);
            zip.write("harmless sample for parser reachability checks\n".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
    }
}

