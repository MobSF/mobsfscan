class ZipSamples {
    void unzip(String zipPath, String destDir) throws Exception {
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath));
        ZipEntry entry = zis.getNextEntry();
        // ruleid:android_zip_slip
        File direct = new File(destDir, entry.getName());
        String name = entry.getName();
        // ruleid:android_zip_slip
        File viaName = new File(destDir, name);
        // ok:android_zip_slip
        File safe = new File(destDir, entry.getName());
        if (!safe.getCanonicalPath().startsWith(new File(destDir).getCanonicalPath())) {
            throw new SecurityException();
        }
        String safeName = entry.getName();
        // ok:android_zip_slip
        File safeVia = new File(destDir, safeName);
        String canon = safeVia.getCanonicalPath();
        if (!canon.startsWith(new File(destDir).getCanonicalPath())) {
            throw new SecurityException();
        }
        // ok:android_zip_slip
        File checked = new File(destDir, entry.getName());
        // ruleid:android_zip_slip
        File unchecked = new File(destDir, entry.getName());
        if (!checked.getCanonicalPath().startsWith(new File(destDir).getCanonicalPath())) {
            throw new SecurityException();
        }
        ZipEntry loopEntry;
        while ((loopEntry = zis.getNextEntry()) != null) {
            // ruleid:android_zip_slip
            File looped = new File(destDir, loopEntry.getName());
        }
    }
}
