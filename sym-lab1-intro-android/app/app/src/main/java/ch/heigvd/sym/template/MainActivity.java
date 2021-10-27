/*
 * File     : MainActivity.java
 * Project  : TemplateActivity
 * Author   : Markus Jaton 2 juillet 2014
 * 			  Fabien Dutoit 23 juillet 2019
 *            IICT / HEIG-VD
 *                                       
 * mailto:fabien.dutoit@heig-vd.ch
 * 
 * This piece of code reads a [email_account / password ] combination.
 * It is used as a template project for the SYM module element given at HEIG-VD
 * Target audience : students IL, TS, IE [generally semester 1, third bachelor year]
 *   
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
 * THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
package ch.heigvd.sym.template;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    // For logging purposes
    private static final String TAG = MainActivity.class.getSimpleName();

    // Just for test purposes : please destroy !
	private static final String validEmail      = "toto@tutu.com";
	private static final String validPassword   = "tata";

    // GUI elements
	private EditText email      = null;
	private EditText password	= null;
    private Button   signIn     = null;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate method called");

		// Show the welcome screen / login authentication dialog
		setContentView(R.layout.authent);

		// Link to GUI elements
        this.email      = findViewById(R.id.email);
        this.password 	= findViewById(R.id.password);
        this.signIn     = findViewById(R.id.buttOk);

		// Then program action associated to "Ok" button
		signIn.setOnClickListener((v) -> {

			/*
			 * There you have to check out if the email/password
			 * combination given is valid or not
			 */
			String mail = email.getText().toString();
			String passwd = password.getText().toString();


			// We check here if the mail contains '@' if not we make a toast and keep infos
			if( !mail.contains("@")){
				Toast.makeText(MainActivity.this, getResources().getString(R.string.validemail), Toast.LENGTH_LONG).show();
			} else {

				if (isValid(mail, passwd)) {
					/* Ok, valid combination, do something or launch another activity...
					 * The current activity could be finished, but it is not mandatory.
					 * To launch activity MyActivity.class, try something like :
					 */
					Intent intent = new Intent(this, ch.heigvd.sym.template.MyActivity.class);
					intent.putExtra("emailEntered", mail);
					intent.putExtra("passwordGiven", passwd);
					this.startActivity(intent);
					 /*
					 * Alternately, you could also startActivityForResult if you are awaiting a result.
					 * In the latter case, you have to indicate an int parameter to identify MyActivity
					 *
					 * If you haven't anything more to do, you may finish()...
					 * But just display a small message before quitting...
					 */
					Toast.makeText(MainActivity.this, getResources().getString(R.string.good), Toast.LENGTH_LONG).show();
					//finish();
				} else {
					// Wrong combination, display pop-up dialog and stay on login screen
					showErrorDialog(mail, passwd);
				}
			}
		});
	}
	
	private boolean isValid(String mail, String passwd) {
        if(mail == null || passwd == null) {
            Log.w(TAG, "isValid(mail, passwd) - mail and passwd cannot be null !");
            return false;
        }
		// Return true if combination valid, false otherwise
		return (mail.equals(validEmail) && passwd.equals(validPassword));
	}

	private void showErrorDialog(String mail, String passwd) {
		/*
		 * Pop-up dialog to show error
		 */
		AlertDialog.Builder alertbd = new AlertDialog.Builder(this);
        alertbd.setIcon(android.R.drawable.ic_dialog_alert);
		alertbd.setTitle(R.string.wronglogin);
	    alertbd.setMessage(R.string.wrong);
	    alertbd.setPositiveButton(android.R.string.ok, (dialog, which) -> {
	    	// When the alert ii closed we erase the fields
			email.setText("");
			password.setText("");
			// we do nothing...
			// dialog close automatically
	    });
	    alertbd.create().show();
	}

	@Override
	protected void onStart() {
		super.onStart();
		Log.i(TAG, "onStart method called");
	}

	@Override
	protected void onResume() {
		super.onResume();
		Log.i(TAG, "onResume method called");
	}

	@Override
	protected void onPause() {
		super.onPause();
		Log.i(TAG, "onPause method called");
	}

	@Override
	protected void onStop() {
		super.onStop();
		Log.i(TAG, "onStop method called");
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
		Log.i(TAG, "onDestroy method called");
	}

	@Override
	protected void onRestart() {
		super.onRestart();
		Log.i(TAG, "onRestart method called");
	}
}
