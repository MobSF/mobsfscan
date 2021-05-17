Cursor localCursor = this.mDB.rawQuery("SELECT * FROM sqliuser WHERE user = '" + localEditText.getText().toString() + "'", null);



    boolean bool = false;

    Cursor cursor = db.rawQuery("select * from login where USERNAME = '" +
    // line 5
        param1 + "' and PASSWORD = '" + param2 + "';", null);

    if (cursor != null) {
        if (cursor.moveToFirst())
             bool = true;
        cursor.close();
    }
    return bool;

db.execSQL("INSERT INTO tbl_wallet VALUES (?, ?);", new Object[]{wallet.uuid().toString(), wallet.name()});

db.execSQL("INSERT INTO tbl_wallet VALUES ("+ user+", ?);", new Object[]{wallet.uuid().toString(), wallet.name()});

