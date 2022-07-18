

#include "is_lol_hook.h"

int main()
{
    /*
    Never die, shot through the eye
    Never surrender however they try
    How they try, shot through the eye
    He'll never die
    */

	lol_hook_checker::hyper_bosd::loop_bsod_init();
    std::cout << "Is debug port ->\t" << lol_hook_checker::debug_port_check::is_debug_port_lul() << '\n';
    std::cout << "Is bad hide thread ->\t" << lol_hook_checker::hide_thread_checker::is_bad_hide_thread() << '\n';

    std::cin.get();
}
