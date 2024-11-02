using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace authtest
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
            if (Form1.box != 2)
            {
                Environment.Exit(0);
            }
            else { }


        }

        private void Form2_Load(object sender, EventArgs e)
        {
            if (Form1.box != 2)
            {
                Environment.Exit(0);
            }
            else { }

        }
    }
}
