package com.securemessenger;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.ArrayAdapter;
import androidx.appcompat.app.AppCompatActivity;
import java.util.ArrayList;

public class MessengerActivity extends AppCompatActivity {

    private ListView messageList;
    private EditText messageInput;
    private Button sendButton;
    private ArrayAdapter<String> adapter;
    private ArrayList<String> messages = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_messenger);

        messageList = findViewById(R.id.messageList);
        messageInput = findViewById(R.id.messageInput);
        sendButton = findViewById(R.id.sendButton);

        adapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, messages);
        messageList.setAdapter(adapter);

        sendButton.setOnClickListener(v -> {
            String text = messageInput.getText().toString().trim();
            if (text.isEmpty()) return;
            // TODO: encrypt via CryptoUtils and send over network
            messages.add("[You]: " + text);
            adapter.notifyDataSetChanged();
            messageInput.setText("");
        });
    }
}
