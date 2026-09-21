final DatePicker dp2 = (DatePicker) findViewById(R.id.datePick2);
final Button btn2 = (Button) findViewById(R.id.btnDate2);
final EditText passwordField = (EditText) findViewById(R.id.password);
// ruleid:android_hidden_ui
passwordField.setVisibility(View.GONE);
// ruleid:android_hidden_ui
passwordField.setVisibility(View.INVISIBLE);
// ruleid:android_hidden_ui
int gone = View.GONE;
passwordField.setVisibility(gone);
// ruleid:android_hidden_ui
int invisible = View.INVISIBLE;
passwordField.setVisibility(invisible);
// ok:android_hidden_ui
dp2.setVisibility(View.GONE);
// ok:android_hidden_ui
btn2.setVisibility(View.INVISIBLE);

btn2.setOnClickListener(new View.OnClickListener() {
    public void onClick(View arg0) {
        TextView txt2 = (TextView) findViewById(R.id.txt2);
        txt2.setText("You selected " + dp2.getDayOfMonth()
            + "/" + (dp2.getMonth() + 1) + "/" + dp2.getYear());
    }
});