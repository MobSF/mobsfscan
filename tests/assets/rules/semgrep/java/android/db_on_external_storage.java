class DbSamples {
    void filesConcat(Context context) {
        String path = context.getExternalFilesDir(null).getPath() + "/app.db";
        // ruleid:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase(path, null);
    }

    void envDir() {
        String path = Environment.getExternalStorageDirectory().getPath() + "/app.db";
        // ruleid:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase(path, null);
    }

    void directConcat() {
        SQLiteDatabase.openOrCreateDatabase(
            // ruleid:android_db_on_external_storage
            Environment.getExternalStorageDirectory() + "/x.db", null);
    }

    void envFile() {
        File db = new File(Environment.getExternalStorageDirectory(), "app.db");
        // ruleid:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase(db, null);
    }

    void filesFile(Context context) {
        File db = new File(context.getExternalFilesDir(null), "app.db");
        // ruleid:android_db_on_external_storage
        SQLiteDatabase.openOrCreateDatabase(db.getAbsolutePath(), null);
    }

    void publicDir() {
        File dir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_DOCUMENTS);
        File db = new File(dir, "app.db");
        // ruleid:android_db_on_external_storage
        SQLiteDatabase.openDatabase(db.getPath(), null, SQLiteDatabase.OPEN_READWRITE);
    }

    void inline(Context context) {
        SQLiteDatabase.openOrCreateDatabase(
            // ruleid:android_db_on_external_storage
            new File(context.getExternalFilesDir(null), "app.db"), null);
    }

    void room(Context context, Class<AppDb> cls) {
        Room.databaseBuilder(
            context,
            cls,
            // ruleid:android_db_on_external_storage
            context.getExternalFilesDir(null).getAbsolutePath() + "/app.db");
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
        super(
            context,
            // ruleid:android_db_on_external_storage
            Environment.getExternalStorageDirectory().getAbsolutePath() + "/app.db",
            null,
            1);
    }
}

class HelperFiles extends SQLiteOpenHelper {
    HelperFiles(Context context) {
        super(
            context,
            // ruleid:android_db_on_external_storage
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
