
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            Cursor cursor = db.rawQuery("SELECT * FROM " + TABLE_DATA, null);

            DatabaseRecord record = null;
            if (cursor.moveToFirst()) {
                do {
                    record = new DatabaseRecord();
                    record.setId(Integer.parseInt(cursor.getString(0)));
                    record.setTitle(cursor.getString(1));
                    record.setAuthor(cursor.getString(2));

                    // Add record to records
                    records.add(record);
                } while (cursor.moveToNext());
            }

            Log.d("htbridge", "getAllRecords(): " + records.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return records;

  // Create a network interceptor
        CTInterceptorBuilder builder = new CTInterceptorBuilder()
            .setFailOnError(isFailOnError)
            .setLogger(defaultLogger)
            .setDiskCache(new AndroidDiskCache(getApplication()));

        for (String host : hosts) {
            builder.includeHost(host);
        }

        Interceptor networkInterceptor = builder.build();

        // Set the interceptor when creating the OkHttp client
        return new OkHttpClient.Builder()
            .addNetworkInterceptor(networkInterceptor)
            .build();