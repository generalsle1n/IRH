using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace IRH.Ui.ViewModels.Template;

public partial class AzureDateViewModel : ViewModelBase
{
    [ObservableProperty]
    DateTime _selectedStartDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
    [ObservableProperty]
    DateTime _selectedEndDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
    [ObservableProperty]
    TimeSpan _selectedStartTime = new TimeSpan(0, 0, 0);
    [ObservableProperty]
    TimeSpan _selectedEndTime = new TimeSpan(23, 59, 59);
}