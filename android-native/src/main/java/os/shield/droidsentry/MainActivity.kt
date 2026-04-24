package os.shield.droidsentry

import android.os.Bundle
import com.getcapacitor.BridgeActivity

class MainActivity : BridgeActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(ShieldPlugin::class.java)
        super.onCreate(savedInstanceState)
    }
}
