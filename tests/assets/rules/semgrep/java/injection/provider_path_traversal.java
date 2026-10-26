class BadProvider {
    ParcelFileDescriptor openFile(Uri uri, String mode) throws Exception {
        // ruleid:android_provider_path_traversal
        File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
        // ruleid:android_provider_path_traversal
        File byPath = new File(uri.getPath());
        // ruleid:android_provider_path_traversal
        File byEncoded = new File(uri.getEncodedPath());
        String name = uri.getLastPathSegment();
        // ruleid:android_provider_path_traversal
        File viaName = new File(getContext().getFilesDir(), name);
        String unused = getContext().getFilesDir().getCanonicalPath();
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    ParcelFileDescriptor openAssetFile(Uri uri, String mode) {
        // ruleid:android_provider_path_traversal
        return ParcelFileDescriptor.open(new File(uri.getPath()), 0);
    }

    ParcelFileDescriptor openTypedAssetFile(Uri uri, String mime) {
        // ruleid:android_provider_path_traversal
        return ParcelFileDescriptor.open(new File(uri.getEncodedPath()), 0);
    }
}

class GoodProvider {
    ParcelFileDescriptor openFile(Uri uri, String mode) throws Exception {
        // ok:android_provider_path_traversal
        File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
        if (!file.getCanonicalPath().startsWith(
                getContext().getFilesDir().getCanonicalPath())) {
            throw new SecurityException();
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }
}

class GoodPathProvider {
    ParcelFileDescriptor openFile(Uri uri, String mode) throws Exception {
        String name = uri.getPath();
        // ok:android_provider_path_traversal
        File file = new File(getContext().getFilesDir(), name);
        String canon = file.getCanonicalPath();
        if (!canon.startsWith(getContext().getFilesDir().getCanonicalPath())) {
            throw new SecurityException();
        }
        return null;
    }
}

class UnusedCanonicalPath {
    ParcelFileDescriptor openFile(Uri uri, String mode) throws Exception {
        // ruleid:android_provider_path_traversal
        File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
        String unused = file.getCanonicalPath();
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }
}

class NotAProvider {
    File helper(Uri uri) {
        // ok:android_provider_path_traversal
        return new File(uri.getPath());
    }
}
