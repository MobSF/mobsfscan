class DbSamples {
    void filesConcat(Context context) {
        // ruleid:android_db_on_external_storage
        String path = context.getExternalFilesDir(null).getPath() + "/app.db";
        SQLiteDatabase.openOrCreateDatabase(path, null);
    }

    void envDir() {
        // ruleid:android_db_on_external_storage
        String path = Environment.getExternalStorageDirectory().getPath() + "/app.db";
        SQLiteDatabase.openOrCreateDatabase(path, null);
    }

    void envFile() {
        // ruleid:android_db_on_external_storage
        File db = new File(Environment.getExternalStorageDirectory(), "app.db");
        SQLiteDatabase.openOrCreateDatabase(db, null);
    }

    void filesFile(Context context) {
        // ruleid:android_db_on_external_storage
        File db = new File(context.getExternalFilesDir(null), "app.db");
        SQLiteDatabase.openOrCreateDatabase(db.getAbsolutePath(), null);
    }

    void publicDir() {
        // ruleid:android_db_on_external_storage
        File dir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_DOCUMENTS);
        File db = new File(dir, "app.db");
        SQLiteDatabase.openDatabase(db.getPath(), null, SQLiteDatabase.OPEN_READWRITE);
    }

    void inline(Context context) {
        // ruleid:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase(
            new File(context.getExternalFilesDir(null), "app.db"), null);
    }

    void internalName(Context context) {
        // ok:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase("app.db", null);
        // ok:android_db_on_external_storage
        context.openOrCreateDatabase("app.db", 0, null);
    }

    void internalFile(Context context) {
        File db = context.getDatabasePath("app.db");
        // ok:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase(db, null);
    }
}

class HelperEnv extends SQLiteOpenHelper {
    HelperEnv(Context context) {
        // ruleid:android_db_on_external_storage
        super(
            context,
            Environment.getExternalStorageDirectory().getAbsolutePath() + "/app.db",
            null,
            1);
    }
}

class HelperFiles extends SQLiteOpenHelper {
    HelperFiles(Context context) {
        // ruleid:android_db_on_external_storage
        super(
            context,
            new File(context.getExternalFilesDir(null), "notes.db").getAbsolutePath(),
            null,
            1);
    }
}

class NotADatabase {
    NotADatabase(Context context) {
        // ok:android_db_on_external_storage
        super(
            context,
            new File(context.getExternalFilesDir(null), "images").getAbsolutePath());
    }
}

class HelperInternal extends SQLiteOpenHelper {
    HelperInternal(Context context) {
        // ok:android_db_on_external_storage
        super(context, "app.db", null, 1);
    }
}
