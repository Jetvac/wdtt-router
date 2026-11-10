package com.wdtt.client.ui.dialogs

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.wdtt.client.ui.utils.stripVkUrlStatic

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HashesDialog(
    hash1: String,
    hash2: String,
    hash3: String,
    hash4: String,
    onSave: (String, String, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var h1 by remember { mutableStateOf(hash1) }
    var h2 by remember { mutableStateOf(hash2) }
    var h3 by remember { mutableStateOf(hash3) }
    var h4 by remember { mutableStateOf(hash4) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(24.dp),
            color = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface,
            tonalElevation = 8.dp
        ) {
            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Tag, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(24.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("VK Хеши", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Закрыть")
                    }
                }

                Text(
                    text = "Больше хешей — выше лимит потоков и лучшее распределение нагрузки.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 4.dp)
                )

                listOf(
                    Triple("VK Хеш 1 *", h1) { v: String -> h1 = v },
                    Triple("VK Хеш 2", h2) { v: String -> h2 = v },
                    Triple("VK Хеш 3", h3) { v: String -> h3 = v },
                    Triple("VK Хеш 4", h4) { v: String -> h4 = v }
                ).forEachIndexed { idx, (label, value, onChange) ->
                    val isShort = value.isNotBlank() && value.length < 16
                    OutlinedTextField(
                        value = value,
                        onValueChange = { raw ->
                            val cleaned = raw.filter { c -> c != ' ' && c != '\n' }
                            onChange(stripVkUrlStatic(cleaned))
                        },
                        label = { Text(label) },
                        placeholder = { Text("Ссылка звонка или хеш") },
                        singleLine = true,
                        isError = isShort,
                        supportingText = if (isShort) {
                            { Text("Хеш ${idx + 1} — короткий (мин. 16)", color = MaterialTheme.colorScheme.error) }
                        } else null,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                    )
                }

                Button(
                    onClick = {
                        onSave(h1, h2, h3, h4)
                    },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = h1.isNotBlank() && h1.length >= 16,
                    colors = ButtonDefaults.buttonColors(contentColor = MaterialTheme.colorScheme.onPrimary)
                ) {
                    Text("Сохранить", fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}
