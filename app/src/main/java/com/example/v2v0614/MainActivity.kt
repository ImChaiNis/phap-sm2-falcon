package com.example.v2v0614

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Surface
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import com.example.v2v0614.ui.screens.TestScreen
import com.example.v2v0614.ui.theme.V2VTheme

/** Endpoint app. No authority private keys, native placeholder SM2, or on-device certificate issuance. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { V2VTheme { Surface(modifier = Modifier.fillMaxSize()) { TestScreen() } } }
    }
}
