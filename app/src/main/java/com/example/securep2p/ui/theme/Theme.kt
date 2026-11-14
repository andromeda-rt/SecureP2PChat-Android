package com.example.securep2p.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val SecureP2PColorScheme = darkColorScheme(
    primary = Accent,
    onPrimary = BgDark,
    primaryContainer = AccentDark,
    onPrimaryContainer = TextPrimary,
    secondary = AccentHover,
    onSecondary = BgDark,
    background = BgDark,
    onBackground = TextPrimary,
    surface = BgSecondary,
    onSurface = TextPrimary,
    surfaceVariant = BgCard,
    onSurfaceVariant = TextSecondary,
    outline = Border,
    error = Danger,
    onError = TextPrimary
)

@Composable
fun Securep2pTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = SecureP2PColorScheme,
        typography = Typography,
        content = content
    )
}
